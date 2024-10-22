from django.shortcuts import render, redirect,get_object_or_404
from django.http import HttpResponse
from myapp.models import *
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Q 

def base(req):
    return render (req, 'base.html')

def password_change(req):
    current_user=req.user
    if req.method == 'POST':
        currentpassword = req.POST.get("currentpassword")
        newpassword = req.POST.get("newpassword")
        confirmpassword = req.POST.get("confirmpassword")

        if check_password(currentpassword,req.user.password):
            if newpassword==confirmpassword:
                current_user.set_password(newpassword)
                current_user.save()
                update_session_auth_hash(req,current_user)
                messages.success(req, "Your password has been changed successfully.")
                return redirect("loginpage")
            
            
            if newpassword != confirmpassword:
                messages.warning(req, "New passwords do not match")
                return redirect('password_change')
            else:
                messages.error(req, "Current password is incorrect")
                return render(req, "password.html")
            
    return render(req, 'password.html')


def loginpage(req):
    if req.method == 'POST':
        username = req.POST.get("username")
        password = req.POST.get("password")

        if not username or not password:
            messages.warning(req, "Both username and password are required")
            return render(req, "loginPage.html")

        user = authenticate(username=username, password=password)

        if user is not None:
            login(req, user)
            messages.success(req, "Login Successfully")
            return redirect("base")
        else:
            messages.error(req, "Invalid username or password")

    return render(req, "login.html")


def registerpage(req):
    if req.method == 'POST':
        username = req.POST.get("username")
        Display_name = req.POST.get("Display_name")
        email = req.POST.get("email")
        user_type = req.POST.get("usertype")
        password = req.POST.get("password")
        confirm_password = req.POST.get("confirm_password")

        # Check for required fields
        if not all([username,Display_name, email, user_type,password, confirm_password]):
            messages.warning(req, "All fields are required")
            return render(req, "signupPage.html")

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            messages.warning(req, "Invalid email format")
            return render(req, "signupPage.html")

        # Check password confirmation
        if password != confirm_password:
            messages.error(req, "Passwords do not match")
            return render(req, "signupPage.html")

        # Password validation
        if len(password) < 4:
            messages.warning(req, "Password must be at least 8 characters long")
            return render(req, "signupPage.html")

        if not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            messages.warning(req, "Password must contain both letters and numbers")
            return render(req, "signupPage.html")

        # Create user
        try:
            user = Custom_user.objects.create_user(
                username=username,
                email=email,
                user_type=user_type,
                password=password,
            )
            if user_type=='jobseeker':
                viewersProfileModel.objects.create(user=user)
                
            elif user_type=='recruiters':
                CreatorProfileModel.objects.create(user=user)

            messages.success(req, "Account created successfully! Please log in.")
            return redirect("loginpage")
        except IntegrityError:
            messages.error(req, "Username or email already exists")
            return render(req, "signupPage.html")

    return render(req, "signupPage.html")

def logoutpage(req):
    logout(req)
    return redirect('loginpage')

#profile:


def Profile(req):
    current_user=req.user

    edu=CreatorProfileModel.objects.filter(user=current_user)
    exp=viewersProfileModel.objects.filter(user=current_user)
    Skills=Skills_Model.objects.filter(user=current_user)
    text={
        'edu':edu,
        'exp':exp,
        'Skills':Skills,
    }
 
    return render(req,'profile.html',text)



def updateprofile(req,id):
    current_user=req.user
    
    if req.method=='POST':
        username=req.POST.get("username")
        email=req.POST.get("email")
        first_name=req.POST.get("first_name")
        last_name=req.POST.get("last_name")
        company_logo_old=req.POST.get("company_logo_old")
        Image=req.FILES.get("Image")
        
        
        current_user.username=username
        current_user.email=email
        current_user.first_name=first_name
        current_user.last_name=last_name
        
        
        try:
            creatorProfile=CreatorProfileModel.objects.get(user=current_user)
            if Image:
                creatorProfile.Image=Image
                creatorProfile.save()
                current_user.save()

            else:
                creatorProfile.Image=company_logo_old
                creatorProfile.save()
                current_user.save()
            
            return redirect("Profile")
            
        except CreatorProfileModel.DoesNotExist:
            creatorProfile=None
            
        try:
            viewersProfile=viewersProfileModel.objects.get(user=current_user)

            if Image:
                viewersProfile.Image=Image
                viewersProfile.save()
                current_user.save()

            else:
                viewersProfile.Image=company_logo_old
                viewersProfile.save()
                current_user.save()

            
            return redirect("Profile")
            
        except viewersProfileModel.DoesNotExist:
            viewersProfile=None

    return render (req,'updateprofile.html')
    data=Skills_Model.objects.filter(id=id)
    data.delete()
    return redirect('skill_list')