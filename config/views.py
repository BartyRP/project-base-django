from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib import messages
from .forms import  LoginForm, UserRegistrationForm
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.models import User
# Create your views here.

def indexHome(request):
    user = request.user
    return render(request, 'indexHomee.html', {'user': user})

def login_view(request):
    user = request.user
    form = LoginForm(request.POST or None)
    msg = None
    if request.method == 'POST':
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            if username == '' or password == '':
                msg = 'Los campos son requeridos'
            else:
                user = authenticate(username=username, password=password)
                if user is not None and not user.is_active:
                    messages.add_message(request=request, level=messages.ERROR,
                             message="El correo ingresado no se encuentra validado, verifique su ")
                    return redirect('indexHome')
                if user is not None:
                    login(request, user)
                    messages.add_message(request=request, level=messages.SUCCESS,
                             message="Bienvenido " + user.username + "! Has iniciado sesión correctamente")
                    return redirect('indexHome')
                else:
                    #Datos no validos
                    messages.add_message(request=request, level=messages.ERROR,
                             message="Los datos ingresados no son correctos")
                    return redirect('indexHome')
        else:
            msg = 'Error al validar forumulario'
    return render(request, 'login.html', {'form': form, 'msg': msg})

def logout_view(request):
    msg = None
    user = request.user
    if user.is_authenticated:
        logout(request)

        messages.add_message(request=request, level=messages.SUCCESS,
                             message="Sesión cerrada correctamente")
        return redirect('indexHome')



def register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        # Get email from form
        if form.is_valid():
            user = form.save(commit=False)
            if User.objects.filter(email=user.email).exists():
                messages.error(request, "El correo ya existe")
                return redirect('register')
            else:
                user.is_active=False
                user.save()
                activateEmail(request, user, form.cleaned_data.get('email'))
                return redirect('indexHome')

        else:
            for error in list(form.errors.values()):
                messages.error(request, error)

    else:
        form = UserRegistrationForm()

    return render(
        request=request,
        template_name="register.html",
        context={"form": form}
        )

def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    message = render_to_string("template_activate_account.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Se ha enviado un correo de verificación a tu bandeja de entrada.')
    else:
        messages.error(request, f'Ha ocurrido un problema al enviar el correo a {to_email}, verificar que se ha ingresado correctamente.')


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Gracias por registrarte en Trombosis.cl, ahora tu cuenta se encuentra validada y puedes ingresar sesión.")
        return redirect('login')
    else:
        messages.error(request, "Activation link is invalid!")

    return redirect('homepage')