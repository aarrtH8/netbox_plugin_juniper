from django import forms


class SSHForm(forms.Form):
    ssh_user = forms.CharField(
        label='SSH User',
        initial='juniper',
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    ssh_pass = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='SSH Password'
    )