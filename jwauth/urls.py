from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    UserView,
    LogoutView,
    TaskView,
    TaskPostView,
    VerifyEmail,
    SetNewPasswordAPIView,
    RequestPasswordReset,
    # PasswordTokenCheckAPI,
    SetNewPasswordKnownAPIView
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('task/<int:pk>', TaskView.as_view(), name="taskpatch"),
    path('task', TaskPostView.as_view(), name="task"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordReset.as_view(),
         name="request-reset-email"),
    # path('password-reset/<uidb64>/<token>/',
    #      PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),
    path(
        'password-reset-known',
        SetNewPasswordKnownAPIView.as_view(),
        name='password-reset-known'
    )
]
