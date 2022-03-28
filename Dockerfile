FROM python:3.8-slim-buster
RUN apt-get update
COPY . .
RUN pip3 install Flask
RUN pip3 install -r requirements.txt
#RUN export FLASK_APP=backend.py
#RUN export FLASK_ENV=development
CMD FLASK_APP=backend.py python3 -m flask run --host=0.0.0.0
