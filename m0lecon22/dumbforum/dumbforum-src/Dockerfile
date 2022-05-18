# syntax=docker/dockerfile:1
FROM python:latest

ENV FLASK_APP=main.py

WORKDIR /microforum
COPY --chown=root:root requirements.txt .
RUN pip3 install -r requirements.txt

COPY --chown=root:root . .

RUN useradd -ms /bin/bash app
RUN chown -R app:app /microforum

EXPOSE 8090
USER app
ENV FLAG='ptm{d1d_u_f1nd_th3_r1ckr0ll?}'
CMD ["python", "main.py", "--host=0.0.0.0"]
