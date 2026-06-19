from django import forms

class UploadFileForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키 (선택)',
        required=False,
        widget=forms.PasswordInput(attrs={'placeholder': '비워두면 공용 키 사용'}),
        max_length=100
    )
    file = forms.FileField(label='파일 선택', required=False)

class FolderScanForm(forms.Form):
    api_key = forms.CharField(
        label='VirusTotal API 키 (선택)',
        required=False,
        widget=forms.PasswordInput(attrs={'placeholder': '비워두면 공용 키 사용'}),
        max_length=100
    )
