#!/bin/zsh

docker build -t sunshuangcheng/certificate-image . \
&& docker run \
-d \
-p 1212:1212 \
-v /Users/sunshuangcheng/Docker/mec/logs:/var/certificate/logs \
--name CertificateServiceContainer \
sunshuangcheng/certificate-image
