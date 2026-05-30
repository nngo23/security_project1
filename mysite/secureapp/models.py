from django.db import models
from django.contrib.auth.models import User

class Post(models.Model):
    creator = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    posted_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.creator.username}: {self.message[:40]}"

class NetworkTrace(models.Model):
    address = models.TextField()
    traced_at = models.DateTimeField(auto_now_add=True)
    excerpt = models.TextField(blank=True)
