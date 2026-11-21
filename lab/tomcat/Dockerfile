FROM tomcat:11-jre21-temurin
RUN cp -a webapps.dist/ROOT webapps.dist/manager webapps/ \
 && sed -i 's#127.0.0.0/8,::1/128#127.0.0.0/8,::1/128,172.30.0.0/24#' webapps/manager/META-INF/context.xml
