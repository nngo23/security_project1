from django.urls import path
from . import views

urlpatterns = [
    path("",              views.board,           name="board"),
    path("join/",         views.new_account,     name="new_account"),
    path("join-old/",     views.new_account_old, name="new_account_old"),
    path("signin/",       views.sign_in,         name="sign_in"),
    path("signin-muted/", views.sign_in_muted,   name="sign_in_muted"),
    path("signout/",      views.sign_out,        name="sign_out"),
    path("push-post/",    views.push_post,       name="push_post"),
    path("pull-url/",     views.pull_url,        name="pull_url"),
]