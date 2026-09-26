import re
from pathlib import Path

from django import forms
from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.forms.models import ModelForm

from .models import Audit
from .services import RouterOSExportValidator


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9]+$")
UPPERCASE_PASSWORD_MESSAGE = "Password must contain at least one uppercase letter."


def _blank_password_help(form, password1="password1", password2="password2"):
    if password1 in form.fields:
        form.fields[password1].help_text = ""
        form.fields[password1].widget.attrs.setdefault("autocomplete", "new-password")
    if password2 in form.fields:
        form.fields[password2].help_text = "Enter the same password as before, for verification."
        form.fields[password2].widget.attrs.setdefault("autocomplete", "new-password")


def _configure_username_field(form):
    if "username" not in form.fields:
        return

    form.fields["username"].help_text = (
        "Use letters and numbers only. Username must be unique."
    )
    form.fields["username"].widget.attrs.update(
        {
            "autocomplete": "username",
            "pattern": "[A-Za-z0-9]+",
            "title": "Use letters and numbers only.",
        }
    )


def _clean_alphanumeric_unique_username(username, instance=None):
    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        raise forms.ValidationError(
            "Username can contain letters and numbers only."
        )

    duplicate = User.objects.filter(username__iexact=username)
    if instance and instance.pk:
        duplicate = duplicate.exclude(pk=instance.pk)

    if duplicate.exists():
        raise forms.ValidationError("This username is already taken.")

    return username


def _clean_complete_email(email):
    email = email.strip().lower()
    domain = email.rsplit("@", 1)[-1]

    if (
        "." not in domain
        or domain.startswith(".")
        or domain.endswith(".")
        or ".." in domain
    ):
        raise forms.ValidationError("Enter a valid email address.")

    return email


def _validate_password_has_uppercase(password):
    if password and not any(char.isupper() for char in password):
        raise forms.ValidationError(UPPERCASE_PASSWORD_MESSAGE)


def _add_uppercase_password_help(field):
    help_text = str(field.help_text or "").strip()
    extra = "Your password must contain at least one uppercase letter."
    field.help_text = f"{help_text} {extra}".strip()


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _configure_username_field(self)
        _blank_password_help(self)

    def clean_username(self):
        return _clean_alphanumeric_unique_username(
            self.cleaned_data["username"]
        )

    def clean_email(self):
        email = _clean_complete_email(self.cleaned_data["email"])
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account already uses this email address.")
        return email

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        _validate_password_has_uppercase(password)
        return password

    def _post_clean(self):
        ModelForm._post_clean(self)
        password = self.cleaned_data.get("password1")
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except ValidationError as error:
                self.add_error("password1", error)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"].lower()
        user.is_staff = False
        user.is_superuser = False
        user.is_active = True
        if commit:
            user.save()
        return user


class ProfileUpdateForm(forms.ModelForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                "placeholder": "name@example.com",
                "autocomplete": "email",
            }
        ),
    )

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
        )
        widgets = {
            "first_name": forms.TextInput(
                attrs={
                    "placeholder": "First name",
                    "autocomplete": "given-name",
                }
            ),
            "last_name": forms.TextInput(
                attrs={
                    "placeholder": "Last name",
                    "autocomplete": "family-name",
                }
            ),
        }

    def clean_email(self):
        email = _clean_complete_email(self.cleaned_data["email"])

        duplicate = User.objects.filter(
            email__iexact=email,
        ).exclude(
            pk=self.instance.pk,
        )

        if duplicate.exists():
            raise forms.ValidationError(
                "Another account already uses this email address."
            )

        return email


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True

    def clean_email(self):
        email = _clean_complete_email(self.cleaned_data["email"])
        qs = User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("An account already uses this email address.")
        return email


class ProfilePasswordForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "new_password1" in self.fields:
            self.fields["new_password1"].widget.attrs.setdefault(
                "autocomplete",
                "new-password",
            )
            _add_uppercase_password_help(self.fields["new_password1"])
        if "new_password2" in self.fields:
            self.fields["new_password2"].help_text = (
                "Enter the same password as before, for verification."
            )
            self.fields["new_password2"].widget.attrs.setdefault(
                "autocomplete",
                "new-password",
            )

    def clean_new_password1(self):
        password1 = self.cleaned_data.get("new_password1")
        if password1:
            _validate_password_has_uppercase(password1)
            try:
                password_validation.validate_password(password1, self.user)
            except ValidationError as error:
                raise ValidationError(error.messages)
        return password1

    def clean_new_password2(self):
        password1 = self.cleaned_data.get("new_password1")
        password2 = self.cleaned_data.get("new_password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                self.error_messages["password_mismatch"],
                code="password_mismatch",
            )
        return password2


class AdminUserCreateForm(UserCreationForm):
    ACCESS_LEVEL_CHOICES = (
        ("user", "Normal user"),
        ("admin", "Administrator"),
    )

    ACCOUNT_STATUS_CHOICES = (
        ("active", "Active"),
        ("inactive", "Inactive"),
    )

    email = forms.EmailField(required=True)

    access_level = forms.ChoiceField(
        choices=ACCESS_LEVEL_CHOICES,
        initial="user",
        label="Access level",
    )

    account_status = forms.ChoiceField(
        choices=ACCOUNT_STATUS_CHOICES,
        initial="active",
        label="Account status",
    )

    class Meta:
        model = User
        fields = (
            "username",
            "first_name",
            "last_name",
            "email",
            "access_level",
            "account_status",
            "password1",
            "password2",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _configure_username_field(self)
        if "password1" in self.fields:
            _add_uppercase_password_help(self.fields["password1"])

    def clean_username(self):
        return _clean_alphanumeric_unique_username(
            self.cleaned_data["username"]
        )

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        _validate_password_has_uppercase(password)
        return password

    def clean_email(self):
        email = _clean_complete_email(self.cleaned_data["email"])

        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "An account already uses this email address."
            )

        return email

    def save(self, commit=True):
        user = super().save(commit=False)

        access_level = self.cleaned_data["access_level"]
        account_status = self.cleaned_data["account_status"]

        user.email = self.cleaned_data["email"]
        user.is_active = account_status == "active"
        user.is_staff = access_level == "admin"
        user.is_superuser = access_level == "admin"

        if commit:
            user.save()

        return user


class AdminUserUpdateForm(forms.ModelForm):
    ACCESS_LEVEL_CHOICES = (
        ("user", "Normal user"),
        ("admin", "Administrator"),
    )

    ACCOUNT_STATUS_CHOICES = (
        ("active", "Active"),
        ("inactive", "Inactive"),
    )

    email = forms.EmailField(required=True)

    access_level = forms.ChoiceField(
        choices=ACCESS_LEVEL_CHOICES,
        label="Access level",
    )

    account_status = forms.ChoiceField(
        choices=ACCOUNT_STATUS_CHOICES,
        label="Account status",
    )

    class Meta:
        model = User
        fields = (
            "username",
            "first_name",
            "last_name",
            "email",
            "access_level",
            "account_status",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _configure_username_field(self)

        self.fields["access_level"].initial = (
            "admin"
            if self.instance.is_superuser
            else "user"
        )

        self.fields["account_status"].initial = (
            "active"
            if self.instance.is_active
            else "inactive"
        )

    def clean_username(self):
        return _clean_alphanumeric_unique_username(
            self.cleaned_data["username"],
            instance=self.instance,
        )

    def clean_email(self):
        email = _clean_complete_email(self.cleaned_data["email"])

        duplicate = User.objects.filter(
            email__iexact=email,
        ).exclude(pk=self.instance.pk)

        if duplicate.exists():
            raise forms.ValidationError(
                "An account already uses this email address."
            )

        return email

    def save(self, commit=True):
        user = super().save(commit=False)

        access_level = self.cleaned_data["access_level"]
        account_status = self.cleaned_data["account_status"]

        user.email = self.cleaned_data["email"]
        user.is_active = account_status == "active"
        user.is_staff = access_level == "admin"
        user.is_superuser = access_level == "admin"

        if commit:
            user.save()

        return user


class AdminSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "new_password1" in self.fields:
            _add_uppercase_password_help(self.fields["new_password1"])

    def clean_new_password1(self):
        password1 = self.cleaned_data.get("new_password1")
        _validate_password_has_uppercase(password1)
        return password1


class AuditUploadForm(forms.ModelForm):
    class Meta:
        model = Audit
        fields = ("title", "config_file")
        widgets = {
            "title": forms.TextInput(attrs={"placeholder": "e.g. Lab router check"}),
            "config_file": forms.ClearableFileInput(
                attrs={
                    "accept": ".rsc,.txt",
                    "class": "file-input",
                }
            ),
        }

    def clean_config_file(self):
        uploaded = self.cleaned_data["config_file"]
        suffix = Path(uploaded.name).suffix.lower()
        if suffix not in {".rsc", ".txt"}:
            raise forms.ValidationError("Upload a MikroTik .rsc or plain-text .txt export.")
        if uploaded.size > settings.NETAUDIT_MAX_UPLOAD_SIZE_BYTES:
            raise forms.ValidationError(
                f"The configuration file must not exceed {settings.NETAUDIT_MAX_UPLOAD_SIZE_MB} MB."
            )
        sample = uploaded.read()
        uploaded.seek(0)
        if b"\x00" in sample[:4096]:
            raise forms.ValidationError("The uploaded file appears to be binary, not a text export.")
        for encoding in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                text = sample.decode(encoding)
                break
            except UnicodeDecodeError:
                text = ""
        if not text:
            raise forms.ValidationError("The uploaded file encoding is not supported.")
        try:
            RouterOSExportValidator().validate(text)
        except ValueError as error:
            raise forms.ValidationError(str(error)) from error
        return uploaded

