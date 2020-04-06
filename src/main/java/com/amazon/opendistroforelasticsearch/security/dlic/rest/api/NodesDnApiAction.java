package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NodesDnValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class NodesDnApiAction extends PatchableResourceApiAction {
    public static final String STATIC_ES_YML_NODES_DN = "STATIC_ES_YML_NODES_DN";
    private final List<String> staticNodesDnFromEsYml;

    @Inject
    public NodesDnApiAction(
        final Settings settings, final Path configPath, final RestController controller, final Client client, final AdminDNs adminDNs,
        final IndexBaseConfigurationRepository cl, final ClusterService cs, final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.staticNodesDnFromEsYml = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList());
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

    protected void consumeParameters(final RestRequest request) {
        request.param("name");
        request.param("show_all");
    }

    @Override
    protected boolean isReadOnlyAndAccessible(Settings settings, String name) {
        if (STATIC_ES_YML_NODES_DN.equals(name)) {
            return false;
        }
        return super.isReadOnlyAndAccessible(settings, name);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, Builder additionalSettings)
        throws IOException{

        final String resourcename = request.param("name");

        final Tuple<Long, Builder> settingsBuilder = load(getConfigName(), true);

        // filter hidden resources and sensitive settings
        filter(settingsBuilder.v2());

        Settings configurationSettings = settingsBuilder.v2().build();

        // no specific resource requested, return complete config
        if (resourcename == null || resourcename.length() == 0) {
            final Boolean showAll = request.paramAsBoolean("show_all", Boolean.FALSE);
            if (showAll) {
                configurationSettings = Settings.builder()
                    .putList(STATIC_ES_YML_NODES_DN, this.staticNodesDnFromEsYml)
                    .put(configurationSettings)
                    .build();
            }
            channel.sendResponse(
                new BytesRestResponse(RestStatus.OK, convertToJson(channel, configurationSettings)));
            return;
        }

        final Map<String, Object> con =
            new HashMap<>(Utils.convertJsonToxToStructuredMap(Settings.builder().put(configurationSettings).build()))
                .entrySet()
                .stream()
                .filter(f->f.getKey() != null && f.getKey().equals(resourcename)) //copy keys
                .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));

        if (!con.containsKey(resourcename)) {
            notFound(channel, "Resource '" + resourcename + "' not found.");
            return;
        }

        channel.sendResponse(
            new BytesRestResponse(RestStatus.OK, XContentHelper.convertToJson(Utils.convertStructuredMapToBytes(con), false, false, XContentType.JSON)));
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
        return ConfigConstants.CONFIGNAME_NODES_DN;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new NodesDnValidator(request, isSuperAdmin(), ref, this.settings, params);
    }
}
