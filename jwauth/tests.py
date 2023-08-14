from rest_framework import status
from django.test import TestCase
from django.urls import reverse
from .models import User
from django.test.utils import override_settings
from http.cookies import SimpleCookie
from rest_framework.test import APITestCase
# Create your tests here.

# class to define a test case for login
class UserLoginTestCase(APITestCase):

    # some setup here, explained later

    def test_correct_registration(self):
        # unit test
        # Corroborate the expected scenario
        url = reverse('register')
        reg_resp = self.client.post(url, {'username':'user@foo.com', 'password':'pass'}, format='json')
        auth_headers = {
            'HTTP_AUTHORIZATION': reg_resp.data.get("token"),
        }
        self.assertEqual(reg_resp.status_code, status.HTTP_201_CREATED)
        self.assertTrue('email_body' in reg_resp.data)
        # verification_url = reverse('email-verify')
        # ver_resp = self.client.get(verification_url, headers=auth_headers, format='json')
        # print(ver_resp.data)
        # self.assertEqual(ver_resp.status_code, status.HTTP_200_OK)

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
            format='json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        login_url = reverse('login')
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass123'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_403_FORBIDDEN)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass1234'}, format='json')
        # auth_headers = {
        #     'HTTP_AUTHORIZATION': resp_login.data.get("token"),
        # }
        self.client.credentials(HTTP_AUTHORIZATION = resp_login.data.get("jwt"))
        self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
        reset_known_url = reverse('password-reset-known')
        resp_reset_known = self.client.patch(
            reset_known_url,
            # headers=auth_headers,
            data={
                "old_password": "pass1234",
                "new_password": "pass12345",
                "new_password_again":  "pass12345"
            },
            format='json'
        )
        self.assertEqual(resp_reset_known.status_code, status.HTTP_200_OK)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass1234'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_403_FORBIDDEN)
        resp_login = self.client.post(login_url, {'email':'user@foo.com', 'password':'pass12345'}, format='json')
        self.assertEqual(resp_login.status_code, status.HTTP_200_OK)
        task_post_url = reverse('task')
        for i in range(1,3):
            task_post_status = self.client.post(
                task_post_url,
                {
                    "taskname": f"task{i}", "completion": False
                },
                format='json'
            )
        self.assertEqual(task_post_status.status_code, status.HTTP_201_CREATED)
        task_post_status = self.client.get(task_post_url)
        self.assertEqual(len(task_post_status.data), 2)
        task_patch_status = self.client.patch(
            '/api/task/1',
            data = {
                "taskname": "finishedtask1", "completion": True,
            },
            format='json'
        )
        self.assertEqual(task_patch_status.status_code, status.HTTP_200_OK)
        task_post_status = self.client.get(task_post_url)
        self.assertEqual(
            task_post_status.data[0],
            {
                'id': 1,
                'taskname': 'finishedtask1',
                'completion': True,
                'username_id': 1
            }
        )
        task_delete_status = self.client.delete('/api/task/1')
        task_post_status = self.client.get(task_post_url)
        self.assertEqual(task_post_status.data[0].get('id'), 2)
