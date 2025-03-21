from rest_framework import serializers
from authentication.models import User
import os
import uuid
from authentication.serializers import password_regex, validate_regex
from django.contrib.auth.hashers import make_password

MAX_FILE_SIZE = 2 * 1024 * 1024


class UserProfileSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    remove_profile_picture = serializers.BooleanField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'profile_picture',
                  'password', 'confirm_password', 'remove_profile_picture']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        return validate_regex(value, password_regex,
                              'Password must be 8-30 characters long and include at least one lowercase letter, one uppercase letter, and one number.'
                              )

    def validate(self, data):
        if 'password' in data:
            if 'confirm_password' not in data:
                raise serializers.ValidationError(
                    {"confirm_password": "Confirm password is required."})
            if data['password'] != data['confirm_password']:
                raise serializers.ValidationError(
                    {"confirm_password": "Passwords do not match."})
        return data

    def update(self, instance, validated_data):

        # Image
        new_profile_picture = validated_data.get('profile_picture')
        if new_profile_picture:
            if new_profile_picture.size > MAX_FILE_SIZE:
                raise serializers.ValidationError(
                    {"profile_picture": "File size exceeds the 2MB limit."})

            if instance.profile_picture:
                instance.profile_picture.delete()

            unique_string = f"{instance.username}_picture_{str(uuid.uuid4())}"

            file_extension = os.path.splitext(new_profile_picture.name)[
                1]

            new_filename = f"{unique_string}{file_extension}"

            new_profile_picture.name = new_filename

            instance.profile_picture = new_profile_picture

        # Remove profile pic
        remove_profile_picture = validated_data.get('remove_profile_picture')
        if remove_profile_picture and instance.profile_picture:
            instance.profile_picture.delete()

        # Password
        password = validated_data.get('password')
        if password:
            validated_data['password'] = make_password(password)
        return super().update(instance, validated_data)
