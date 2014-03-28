from django import forms

class NewSensorForm(forms.Form):
	name = forms.CharField(max_length=30, widget=forms.TextInput(attrs={'class': 'form-control'}))
	ipAddress = forms.CharField(max_length=38, widget=forms.TextInput(attrs={'class': 'form-control'}))
	autonomous = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'form-control'}))
