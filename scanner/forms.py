from django import forms

class UploadFileForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키',
        widget=forms.PasswordInput(attrs={'placeholder': 'API 키를 입력하세요'}),
        max_length=100
    )
    file = forms.FileField(label='파일 선택', required=False)

class FolderScanForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키',
        widget=forms.PasswordInput(attrs={'placeholder': 'API 키를 입력하세요'}),
        max_length=100
    )
    files = forms.FileField(
        label='파일 선택 (여러 개 가능)',
        widget=forms.ClearableFileInput(attrs={'multiple': True}),
        required=False
    )