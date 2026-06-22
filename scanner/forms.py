from django import forms

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
