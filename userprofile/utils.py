from rest_framework import permissions


class UserAuth(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and not request.user.is_blocked
