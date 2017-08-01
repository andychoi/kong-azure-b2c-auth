FROM kong

RUN mkdir /pluginsrc
COPY . /pluginsrc
WORKDIR /pluginsrc
RUN luarocks make
ENV KONG_CUSTOM_PLUGINS=azure-b2c-auth
