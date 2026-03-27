# SUCI catcher experiment
This is an implementation of the SUCI-cather attack discussed and implemnted on multiple paper, and my thesis.

## Requirements
OAI basic nrf core network with oaisoftwareallience/oai-*:develop
Follow https://github.com/simula/oai-cn5g-fed/tree/dreibh/simulamet-develop, using docker-compose-basic-nrf.yaml and update the with the following config (PROFILE A & B for protection scheme, taken from OAI):

    udm:
    subscriber_profiles:
        - protection_scheme: 1
        home_network_public_key: '5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650'
        home_network_private_key: 'c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d'
        home_network_public_key_id: 1
        - protection_scheme: 2
        home_network_public_key: '0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4'
        home_network_private_key: 'F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA'
        home_network_public_key_id: 2

## Steps

1. Update to db to match the following db config:
    docker exec mysql mysql -u test --password=test oai_db
  -e "UPDATE AuthenticationSubscription SET encPermanentKey='0C0A34601D4F07677303652C0462535B', encOpcKey='63bfa50ee6523365ff14c1f45f88737d', protectionParameterId='0C0A34601D4F07677303652C0462535B' WHERE ueid='208950000000034';"

    docker exec mysql mysql -u test --password=test oai_db
  -e "UPDATE AuthenticationSubscription SET encPermanentKey='c004bc7e34117399d2046655b77c8283', encOpcKey='9245cd6283cc53ce24ac1186a60dee6b', protectionParameterId='c004bc7e34117399d2046655b77c8283' WHERE ueid='208950000000042';"


2. Enter UERANSIM and build using the DockerFile: docker buildx build -f docker/Dockerfile --tag hamza/ueransim:latest --load .
3. Build the SUCI-catcher attack: docker buildx build --tag suci-catcher:latest --load .
4. Run the SUCI-catcher: docker compose -f attack-sim.yaml up -d suci-catcher
5. Observe traffic using tshark
6. Run the UERANSIM: docker compose -f attack-sim.yaml up -d ueransim

// NB: The current recording is hardcoded into the script and so attack-sim-fail.yaml will lead to MAC-Failure, while attack-sim.yaml will be successfull//