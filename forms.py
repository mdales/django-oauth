from django import forms

class OAuthAuthorizeForm(forms.Form):
    authorize_access = forms.BooleanField(required=True)
    
class OAuthConsumerForm(forms.Form):
    name = forms.CharField(max_length=255)
    url  = forms.URLField(required=False)
    description = forms.CharField(required=False,widget=forms.Textarea())

    