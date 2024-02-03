from flask_wtf import FlaskForm
from wtforms import StringField, RadioField, SelectField, TextAreaField, validators, SubmitField, FileField, PasswordField, HiddenField,IntegerField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Email, NumberRange, Regexp, Length

# feedback form class
class FeedbackForm(FlaskForm):
    first_name = StringField('First Name', [
        validators.Length(min=1, max=150),
        validators.DataRequired(),
        validators.Regexp(r'^[A-Za-z\s\-\'\.]*$',
                          message='Only letters, spaces, hyphens, apostrophes, and periods are allowed.')
    ])

    last_name = StringField('Last Name', [
        validators.Length(min=1, max=150),
        validators.DataRequired(),
        validators.Regexp(r'^[A-Za-z\s\-\'\.]*$',
                          message='Only letters, spaces, hyphens, apostrophes, and periods are allowed.')
    ])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    title = RadioField('Title', choices=[('Feedback', 'Feedback'), ('Enquiry', 'Enquiry'), ('Others', 'Others')], default='F')
    remarks = TextAreaField('Remarks', [validators.DataRequired()])


# report form class
class ReportForm(FlaskForm):
    title = RadioField\
        ('Reason for reporting this comment:',
         choices=[('Self Injury', 'Self Injury'),
                  ('Harassment or bullying', 'Harassment or bullying'),
                  ('Sales or promotion of drugs', 'Sales or promotion of drugs'),
                  ('Sales or promotion of firearms', 'Sales or promotion of firearms'),
                  ('Nudity or pornography', 'Nudity or pornography'),
                  ('Violence or harm', 'Violence or harm'),
                  ('Hate speech or symbols ', 'Hate speech or symbols'),
                  ('Intellectual property violation', 'Intellectual property violation'),
                  ('I just dont like it', 'I just dont like it')]
                  ,default='I just dont like it')
    remarks = TextAreaField('Remarks', [validators.DataRequired()])


class Report_c_Form(FlaskForm):
    title = RadioField\
        ('Reason for reporting this comment:',
         choices=[('Self Injury', 'Self Injury'),
                  ('Harassment or bullying', 'Harassment or bullying'),
                  ('Sales or promotion of drugs', 'Sales or promotion of drugs'),
                  ('Sales or promotion of firearms', 'Sales or promotion of firearms'),
                  ('Nudity or pornography', 'Nudity or pornography'),
                  ('Violence or harm', 'Violence or harm'),
                  ('Hate speech or symbols ', 'Hate speech or symbols'),
                  ('Intellectual property violation', 'Intellectual property violation'),
                  ('I just dont like it', 'I just dont like it')]
                  ,default='I just dont like it')
    remarks = TextAreaField('Remarks', [validators.DataRequired()])


# email form class
class ComposeNewsletterForm(FlaskForm):
    newsletter_content = TextAreaField('Newsletter Content', validators=[
        DataRequired(),
        Regexp(r'^[^<>/]*$', message="Please avoid using <, >, or / characters.")
    ], render_kw={
        "placeholder": "Title:\n\nMain body message:\n\nEnding message..."
    })
    submit = SubmitField('Send Newsletter')

class CommentForm(FlaskForm):
    comment_text = StringField('Comment', validators=[
        DataRequired(),
        Length(max=200),
        Regexp(r'^[^<>/]*$', message="Please avoid using <, >, or / characters.")
    ], render_kw={'required': True})

class EditForm(FlaskForm):
    caption = StringField('Caption', validators=[
        DataRequired(),
        Length(max=200),
        Regexp(r'^[^<>/]*$', message="Please avoid using <, >, or / characters.")
    ], render_kw={'required': True})

class AddPostForm(FlaskForm):
    caption = StringField('Caption', validators=[
        DataRequired(),
        Length(max=200),
        Regexp(r'^[^<>/]*$', message="Please avoid using <, >, or / characters.")
    ])
    photo = FileField('Photo', validators=[DataRequired()])


# login form #
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


class OTPVerificationForm(FlaskForm):
    username = HiddenField()
    stored_otp = HiddenField()
    otp = IntegerField('Enter OTP:', validators=[DataRequired(), NumberRange(min=100000, max=999999)])
    submit = SubmitField('Verify')


# add quiz and questions form #
class CourseForm(FlaskForm):
    course_name = StringField('Course Name', validators=[DataRequired()])
    question_number = IntegerField('Question Number', validators=[DataRequired()])
    total_marks = IntegerField('Total Marks', validators=[DataRequired()])
    course_id = HiddenField('Course ID')  # Add course_id as a hidden field

    def to_dict(self):
        return {
            'course_name': self.course_name.data,
            'question_number': self.question_number.data,
            'total_marks': self.total_marks.data,
            'course_id': self.course_id.data,
        }

class QuestionForm(FlaskForm):
    marks = IntegerField('Marks', validators=[DataRequired()])
    question = StringField('Question', validators=[DataRequired()])
    option1 = StringField('Option 1', validators=[DataRequired()])
    option2 = StringField('Option 2', validators=[DataRequired()])
    option3 = StringField('Option 3', validators=[DataRequired()])
    option4 = StringField('Option 4', validators=[DataRequired()])
    answer = SelectField('Answer', choices=[('Option1', 'Option 1'), ('Option2', 'Option 2'), ('Option3', 'Option 3'), ('Option4', 'Option 4')], validators=[DataRequired()])

class ResultForm(FlaskForm):
    student = StringField('Student', validators=[DataRequired()])  # Assuming Student is a string field
    exam = StringField('Exam', validators=[DataRequired()])  # Assuming Exam is a string field
    marks = IntegerField('Marks', validators=[DataRequired()])
    date = StringField('Date', validators=[DataRequired()])  # Assuming Date is a string field