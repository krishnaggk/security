package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.SslConfigValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.databind.JsonNode;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;

public class OpenDistroSecuritySslConfigAction extends PatchableResourceApiAction {

    private final Boolean allowPutOrPatch;

    @Inject
    public OpenDistroSecuritySslConfigAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                          final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                          final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {

        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        allowPutOrPatch = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ALLOW_SSLCONFIG_MODIFICATION, false);
    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/ssl/config/", this);
        // NOTE: Need to determine allowPutOrPatch from settings because of following flow
        //  1. OpenDistroSecuritySslConfigAction.super()
        //  2. AbstractApiAction()
        //  3. registerHandlers()
        //  4. OpenDistroSecuritySslConfigAction.allowPutOrPatch = settings.getAsBoolean...
        //
        // Due to above flow when registerHandlers is invoked, allowPutOrPatch is not yet initialized
        boolean enablePutOrPatch = null == allowPutOrPatch ?
            settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ALLOW_SSLCONFIG_MODIFICATION, false) :
            allowPutOrPatch;

        if (enablePutOrPatch) {
            controller.registerHandler(Method.PUT, "/_opendistro/_security/api/ssl/config/{name}", this);
            controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/ssl/config/", this);
        }
    }

    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) {
        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);

        filter(configuration);

        successResponse(channel, configuration);
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (request.method() == Method.PATCH && !allowPutOrPatch) {
            notImplemented(channel, Method.PATCH);
        } else {
            super.handleApiRequest(channel, request, client);
        }
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        if (!allowPutOrPatch) {
            notImplemented(channel, Method.PUT);
            return;
        }

        if(!"0".equals(request.param("name"))) {
            badRequestResponse(channel, "name must be config");
            return;
        }

        super.handlePut(channel, request, client, content);
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.DELETE);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new SslConfigValidator(request, ref, this.settings, param);
    }

    @Override
    protected CType getConfigName() {
        return CType.SSLCONFIG;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.SSLCONFIG;
    }

    @Override
    protected String getResourceName() {
        // not needed, no single resource
        return null;
    }

}
