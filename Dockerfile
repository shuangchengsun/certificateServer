FROM python:3.6
ADD resources /code/resources
ADD main.py /code
ADD NetProcess.py /code
ADD CertificateService.py /code
ADD requirements.txt /code
ADD loggerUtil.py /code

WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python","/code/main.py"]
