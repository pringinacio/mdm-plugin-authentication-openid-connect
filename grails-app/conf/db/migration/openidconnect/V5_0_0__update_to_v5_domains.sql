ALTER TABLE openidconnect.authorization_endpoint_parameters
    ADD path TEXT;

ALTER TABLE openidconnect.discovery_document
    ADD path TEXT;

ALTER TABLE openidconnect.openid_connect_provider
    ADD path TEXT;

ALTER TABLE openidconnect.openid_connect_token
    ADD path TEXT;

