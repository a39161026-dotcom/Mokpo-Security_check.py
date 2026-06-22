from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    email = forms.EmailField(
        label='이메일 (악성 파일 탐지 알림용)',
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': '알림 받을 이메일 주소'}),
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class UploadFileForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키 (선택)',
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': '비워두면 공용 키 사용',
            'autocomplete': 'off',
            'autocorrect': 'off',
            'autocapitalize': 'off',
            'spellcheck': 'false',
            'data-lpignore': 'true',
            'data-1p-ignore': 'true',
        }),
        max_length=100
    )
    file = forms.FileField(label='파일 선택', required=False)

class FolderScanForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키 (선택)',
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': '비워두면 공용 키 사용',
            'autocomplete': 'off',
            'autocorrect': 'off',
            'autocapitalize': 'off',
            'spellcheck': 'false',
            'data-lpignore': 'true',
            'data-1p-ignore': 'true',
        }),
        max_length=100
    )
