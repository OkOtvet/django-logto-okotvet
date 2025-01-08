from django.http import HttpResponseRedirect, HttpResponse
from django.views import View
from django.conf import settings

from django.contrib.auth import login
from .logto_init import start_logto_client
from .models import LogtoUser
from asgiref.sync import sync_to_async


class SigninView(View):
    async def get(self, request):
        uri = settings.LOGTO_API_REDIRECT_URI
        client = start_logto_client(request)
        url = await client.signIn(redirectUri=uri)
        return HttpResponseRedirect(redirect_to=url)


class CallbackView(View):
    async def get(self, request):
        print("DEBUG: вызвана функция CallbackView")
        absolute_uri = request.build_absolute_uri()
        client = start_logto_client(request)
        try:
            # Обработка callback
            await client.handleSignInCallback(absolute_uri)

            # Получение информации о пользователе
            user_info = await client.fetchUserInfo()

            user_username = user_info.name
            user_sub = user_info.sub

            # Вывод данных в консоль
            print("User Username:", user_username)
            print("User Sub:", user_sub)

            # Асинхронная проверка существования пользователя
            user = await sync_to_async(
                LogtoUser.objects.filter(username=user_username, sub=user_sub).first
            )()

            if user:
                # Асинхронный вход пользователя
                await sync_to_async(login)(request, user)

                # Перенаправляем в админку
                return HttpResponseRedirect(redirect_to="/admin/")
            else:
                # Если пользователя нет, возвращаем сообщение об ошибке
                return HttpResponse(
                    "Вы не зарегестрированы как пользователь в системе okOtvet",
                    status=403,
                )

        except Exception as e:
            print("Error:", str(e))
            return HttpResponse("Error: " + str(e), status=500)


class LogoutAndForceLoginView(View):
    async def get(self, request):
        try:
            # Инициализируем Logto клиента
            client = start_logto_client(request)

            # Удаляем локальную сессию пользователя (ID Token, Refresh Token, Access Token)
            await client.signOut(
                postLogoutRedirectUri=request.build_absolute_uri("/auth/callback/")
            )

            # Генерация URL для входа с параметром prompt="login"
            redirect_uri = request.build_absolute_uri("/auth/callback/")
            login_url = await client._buildSignInUrl(
                redirectUri=redirect_uri,
                codeChallenge=client._generateCodeChallenge(),  # Генерируем code challenge
                state=client._generateState(),  # Генерируем state для безопасности
                interactionMode="signIn",  # Принудительно открываем форму входа
            )

            # Принудительное добавление prompt="login"
            login_url += "&prompt=login"

            # Перенаправляем пользователя на форму входа Logto
            return HttpResponseRedirect(login_url)
        except Exception as e:
            print("Error during logout and force login:", str(e))
            return HttpResponse(f"Error: {str(e)}", status=500)
