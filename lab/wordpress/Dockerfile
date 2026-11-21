FROM wordpress:cli-php8.4 AS cli
FROM wordpress:php8.4-apache
COPY --from=cli /usr/local/bin/wp /usr/local/bin/wp
COPY --chmod=755 apache2-lab-bootstrap /usr/local/bin/apache2-lab-bootstrap
CMD ["apache2-lab-bootstrap"]
