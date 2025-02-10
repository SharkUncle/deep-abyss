# Install OpenCVE locally for vulnerability management

Here the documentation for the installation process of OpenCVE.

https://docs.opencve.io/deployment/#configuration

***Disclaimer**: the install.sh is not well done. I run it and got errors. I think this is because they want you to subscribe to the SaaS version of the software just maybe, and I'm not an expert.*

This is just a default installation to test OpenCVE, this is not adapted to a specific organization.

The install is not difficult at all, but some modification need to be done first.

1. Modify the install.sh file and add a step to verify/delete old connections to airflow
2. Move the .env and the settings.py files to another location, it will conflict with the container during the `docker compose up -d` command execution
3. Modify the docker-compose.yaml file and the volumes of the werbserver container, in this steps modify the volumes to the .env and the settings.py files you just move

Modify the environments file and change username and password in the `docker/.env`:
- `POSTGRES_PASSWORD`
- `_AIRFLOW_WWW_USER_USERNAME`
- `_AIRFLOW_WWW_USER_PASSWORD`
- `AIRFLOW__CORE__FERNET_KEY`

For the last parameter, use this python code snippet:
```python
from cryptography.fernet import Fernet

fernet_key = Fernet.generate_key()
print(fernet_key.decode())
```

https://airflow.apache.org/docs/apache-airflow/stable/security/secrets/fernet.html#generating-fernet-key

*This is a requirement from the official OpenCVE documentation.*

Parts to modify in the `docker-compose.yaml`:
```yaml
webserver:
    container_name: webserver
    env_file:
      - .env
    build:
      context: ../web/
      args:
        - OPENCVE_REPOSITORY=${OPENCVE_REPOSITORY}
        - OPENCVE_VERSION=${OPENCVE_VERSION}
        - GUNICORN_CMD_ARGS=${GUNICORN_CMD_ARGS}
      dockerfile: Dockerfile
    volumes:
      - ../web/opencve/conf/.env:/app/opencve/web/opencve/conf/.env:ro
      - ../web/opencve/conf/settings.py:/app/opencve/web/opencve/conf/settings.py:ro
      - repositories:/app/repositories/:ro
      - staticfiles:/app/static/
    restart: on-failure
```

The first 2 lines under the `volumes:` part are:
- `../web/opencve/conf/.env` => the new path of the `.env` file you move
- `../web/opencve/conf/settings.py` => the new path for the `settings.py`

The parts after the `:` is the path in the container, it's not needed to be modify.

Before continuing the installation, the `./install.sh init-docker-stack` failed every time, that was a first for me with Airflow. It failed everytime during the `set-airflow-connections` step. The script add a connection for the postgres and redis, but the command fail and the script stop. 

When I go in the `airflow-scheduler` container and check the connections with `airflow connections list`, all the connections to postgres and redis are already available.

I just add a part to delete existing connections, and it worked so I won't touch it anymore, here the code I add:

```bash
set-airflow-connections() {

    export $(grep -v '^#' .env | grep -E '^POSTGRES' | tr '\n' ' ')

    printf "\n--------| %s\n" "Add Airflow connections"
    display-and-exec "deleting Postgresql Airflow connection" "docker exec airflow-scheduler airflow connections delete opencve-postgres"
    display-and-exec "adding Postgresql Airflow connection" "docker exec airflow-scheduler airflow connections add opencve_postgres --conn-uri postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/opencve > /dev/null"
    display-and-exec "deleting Redis Airflow connection" "docker exec airflow-scheduler airflow connections delete opencve-redis"
    display-and-exec "adding Redis Airflow connection" "docker exec airflow-scheduler airflow connections add opencve_redis --conn-uri redis://redis:6379 --conn-extra '{\"db\": 3}' > /dev/null"

    unset POSTGRES_USER
    unset POSTGRES_PASSWORD

}
```

The installation take some times, you can do something useful during some steps, for example when the script import the CVE or the KB.

I run all the installation steps one-by-one, here all the commands:
- init-docker-stack
- clone-repositories
- create-superuser
- import-opencve-kb
- start-opencve-dag
- install-end

Like this I know what command failed and I can check in the `install.sh` file what was going wrong.

During the `create-superuser` part, you will specify the username and password for the administrator account and the email for the alert.

After that, all the steps work perfectly, now it's time to connect to the OpenCVE webserver: `http://localhost/cve/`

At the first connection you can specify an organization and a project, here some example:
- **BikiniBottom**
- **KrustyKrab**

Now like the SaaS version you can add 'Subscriptions' to your project.