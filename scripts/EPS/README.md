Para realizar el cálculo de los EPS, adjunto el siguiente zip que contiene un script epscount.zip que deberá ser ejecutado de acuerdo a lo que describo a continuación:

- Descargar el script en el servidor donde está instalado Wazuh-Manager y moverlo al directorio:

`/var/ossec/logs/archives mv epschat_log.sh /var/ossec/logs/archives`

- Editar el archivo `ossec.conf` en el servidor donde está instalado Wazuh-Manager, modificando el contenido de la etiqueta `<logall>` a “yes”:

`nano /var/ossec/etc/ossec.conf <logall>yes</logall>`

- Reiniciar Wazuh-Manager para aplicar los cambios:

`systemctl restart wazuh-manager`

- Posicionado en la carpeta `archives`, otorgar permisos de ejecución al script:

`cd /var/ossec/logs/archives/ chmod +x epschat_log.sh`

- Ejecutar el script agregando como sufijo el nombre del archivo que contiene los logs, en este caso `archives.log`_**:**_

`./epschat_log.sh.sh archives.log`

- Con eso se obtendrán los EPS en tiempo real a medida que los eventos que lleguen a Wazuh se escriban en `archives.log`:

- Por favor, recuerda deshabilitar `<logall>`, volviendo su valor al “no” original para evitar sobrecargar el almacenamiento del servidor donde está instalado Wazuh-Manager:

`nano /var/ossec/etc/ossec.conf <logall>no</logall>`
