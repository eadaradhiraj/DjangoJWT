from django.test import TestCase
from rest_framework import status
from django.test import TestCase
from django.urls import reverse
from .models import User
from django.core import mail
from django.test.utils import override_settings
from http.cookies import SimpleCookie
from rest_framework.test import APITestCase
# Create your tests here.

# class to define a test case for login
class UserLoginTestCase(TestCase):

    # some setup here, explained later

    def test_correct_registration(self):
        # unit test
        # Corroborate the expected scenario
        url = reverse('register')
        resp = self.client.post(url, {'email':'user@foo.com', 'password':'pass'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue('token' not in resp.data)

        # print(mail.outbox)

        # verification_url = reverse('email-verify')
        # resp = self.client.post(verification_url, {'token': token}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # resp = self.client.post(verification_url, {'token': 'abc'}, format='json')
        # self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        reset_url = reverse('request-reset-email')
        resp_reset = self.client.post(reset_url, {'email':'user@foo.com'}, format='json')
        self.assertEqual(resp_reset.status_code, status.HTTP_200_OK)
        reset_url = reverse('password-reset-complete')
        resp = self.client.patch(
            reset_url,
            data={
                "password": "pass1234",
                "uidb64": resp_reset.data.get("uidb64"),
                "token":  resp_reset.data.get("token")
            },
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        login_url = reverse('login')
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass123'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_403_FORBIDDEN)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass1234'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
        reset_known_url = reverse('password-reset-known')
        resp_reset_known = self.client.patch(
            reset_known_url,
            data={
                "old_password": "pass1234",
                "new_password": "pass12345",
                "new_password_again":  "pass12345"
            },
            content_type='application/json'
        )
        self.assertEqual(resp_reset_known.status_code, status.HTTP_200_OK)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass1234'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_403_FORBIDDEN)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass12345'}, format='json')
        print(resp_login.client.get_cookie("jwt"))
        # self.client.cookies = SimpleCookie()
        self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
        # self.client.credentials(HTTP_AUTHORIZATION='JWT ' + resp_login.data.get("jwt"))
        task_post_url = reverse('task')
        task_post_status = self.client.post(
            task_post_url,
            {
                "taskname": "task1", "completion": False, 'email':'user@foo.com'
            },
            format='json'
        )
        print(task_post_status.data)
        
