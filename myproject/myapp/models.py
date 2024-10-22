from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class Custom_user(AbstractUser):
    USER=[
        ('recruiters','Recruiters'),
        ('jobseeker','Jobseeker')
    ]

    user_type=models.CharField(choices=USER,max_length=100,null=True)
    Display_name=models.CharField(max_length=100,null=True)

    def  __str__(self):
        return f"{self.username}-{self.Display_name}-{self.user_type}"
    
class viewersProfileModel(models.Model):
    user=models.OneToOneField(Custom_user,on_delete=models.CASCADE,related_name='viewersProfile')
    Image=models.ImageField(upload_to='Media/Blog_Pic',null=True)
    
    def __str__(self):
        return f"{self.user.username}"   
    
class CreatorProfileModel(models.Model):
    user = models.OneToOneField(Custom_user, on_delete=models.CASCADE,related_name='creatorProfile')
    Image=models.ImageField(upload_to='Media/Blog_Pic',null=True)
    
    def __str__(self):
        return f"{self.user.username}"
    
class JobModel(models.Model):
    JOB_TYPE_CHOICES = [
        ('fulltime', 'Full-time'),
        ('parttime', 'Part-time'),
    ]

    user = models.ForeignKey(Custom_user, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=255, null=True)
    Number_of_opening = models.PositiveIntegerField(null=True)
    Category = models.CharField(choices=JOB_TYPE_CHOICES,max_length=255, null=True)
    Job_Description = models.TextField(max_length=255, null=True)
    Skills = models.CharField(max_length=255, null=True)
    company_logo=models.ImageField(upload_to='Media/Blog_Pic',null=True)

    def __str__(self):
        return f"{self.user} at {self.job_title}"
    
class ApplyJobModel(models.Model):
    JOB_TYPE_CHOICES = [
        ('fulltime', 'Full-time'),
        ('parttime', 'Part-time'),
    ]

    user = models.ForeignKey(Custom_user, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=255, null=True)
    Number_of_opening = models.PositiveIntegerField(null=True)
    Category = models.CharField(choices=JOB_TYPE_CHOICES,max_length=255, null=True)
    Job_Description = models.TextField(max_length=255, null=True)
    Skills = models.CharField(max_length=255, null=True)
    company_logo=models.ImageField(upload_to='Media/Blog_Pic',null=True)

 
    def __str__(self):
        return f"{self.user} at {self.job_title}"
    
class Skills_Model(models.Model):
    proficiency=[
        ('high','High'),
        ('mideum','mideum'),
        ('low','Low')
    ]

    user=models.ForeignKey(Custom_user,null=True,on_delete=models.CASCADE)
    skill_name=models.CharField(max_length=100, null=True)
    proficiency_level=models.CharField(choices=proficiency,max_length=100, null=True)

    class Meta:
        unique_together=['user','skill_name']

    def  __str__(self):
        return f"{self.user.first_name}-{self.skill_name}"
    
class intermediate_skillmodel(models.Model):
    skill_name=models.CharField(max_length=100,null=True)
    def  __str__(self):
        return f"{self.skill_name}"