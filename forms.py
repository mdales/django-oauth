from django import forms

class OAuthAuthorizeForm(forms.Form):
    authorize_access = forms.BooleanField(required=True)