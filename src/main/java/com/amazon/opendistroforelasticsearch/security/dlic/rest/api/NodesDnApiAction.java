package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NodesDnValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
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

public class NodesDnApiAction extends PatchableResourceApiAction {

    @Inject
    public NodesDnApiAction(
        final Settings settings, final Path configPath, final RestController controller, final Client client, final AdminDNs adminDNs,
        final IndexBaseConfigurationRepository cl, final ClusterService cs, final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        if (settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false)) {
            controller.registerHandler(Method.GET, "/_opendistro/_security/api/nodesdn/{name}", this);
            controller.registerHandler(Method.GET, "/_opendistro/_security/api/nodesdn/", this);
            controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/nodesdn/{name}", this);
            controller.registerHandler(Method.PUT, "/_opendistro/_security/api/nodesdn/{name}", this);
            controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/nodesdn/", this);
            controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/nodesdn/{name}", this);
        }
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for admin.");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.NODESDN;
    }

    @Override
    protected String getResourceName() {
        return "nodesdn";
    }

    @Override
    protected String getConfigName() {
        return ConfigConstants.CONFIGKEY_NODESDN;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new NodesDnValidator(request, isSuperAdmin(), ref, this.settings, params);
    }
}
