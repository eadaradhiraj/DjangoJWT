from django.urls import path
from .views import RegisterView, LoginView, UserView, LogoutView, TaskView, TaskPostView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('task/<int:pk>', TaskView.as_view()),
    path('task', TaskPostView.as_view()),
]
