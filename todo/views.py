from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .forms import TodoForm
from .models import Todo

# Create your views here.
def signupuser(request):
    if request.method == 'GET':
        return render(request, 'todo/signupuser.html',
                      context={'form': UserCreationForm()})
    elif request.method == 'POST':
        usuario = request.POST["username"]
        senha = request.POST["password1"]

        if senha == request.POST["password2"]:
            try:
                user = User.objects.create_user(
                    username=usuario,
                    password=senha)
                user.save()

                login(request, user)
                return redirect('currenttodos')
            except IntegrityError:
                return render(request, 'todo/signupuser.html',
                              context={'form': UserCreationForm(),
                                       'error': 'Usuário já existe!  Escolha outro!'})
        else:
            return render(request, 'todo/signupuser.html',
                          context={'form': UserCreationForm(),
                                   'error': 'Senhas não coincidem!'})

def loginuser(request):
    if request.method == 'GET':
        return render(request, 'todo/login.html', context={'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST["password"])

        if user is None:
            return render(request, 'todo/login.html',
                          context={'form': AuthenticationForm(), 'error': 'Usuário e senha não conferem!'})
        else:
            login(request, user)
            return redirect('currenttodos')

def currenttodos(request):
    todos = Todo.objects.filter(user=request.user, date_completed__isnull=True)

    return render(request, 'todo/currenttodos.html',
                  context={'todos':todos})

def home(request):
    return render(request, 'todo/home.html')

def logoutuser(request):
    if request.method == 'POST':  # Tem que ter isso para evitar problemas com browsers
        logout(request)
        return redirect('home')

def createTodo(request):
    if request.method == 'GET':
        return render(request, 'todo/create.html',
                      context={'form':TodoForm()})
    else:
        try:
            form = TodoForm(request.POST)  # Pega tudo o que vier da página
            new_todo = form.save(commit=False)
            new_todo.user = request.user

            new_todo.save()
            return redirect('currenttodos')
        except ValueError:
            return render(request, 'todo/create.html',
                          context={'form': TodoForm(),
                                   'error':'Erro nos dados!  Verifique'})

def viewtodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk)
    return render(request, 'todo/viewtodo.html',
                  context={'todo':todo})