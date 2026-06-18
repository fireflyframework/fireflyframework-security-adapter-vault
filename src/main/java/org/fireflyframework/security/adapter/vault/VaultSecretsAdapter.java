/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.adapter.vault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.fireflyframework.security.spi.SecretsPort;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * {@link SecretsPort} backed by HashiCorp Vault's KV v2 secrets engine, so credentials are resolved
 * from Vault at runtime rather than living in YAML. Reads {@code /v1/{mount}/data/{name}} and returns
 * the configured field of the secret. <strong>Fail-closed</strong>: a missing secret/field or a
 * transport error yields an error signal so callers can fail fast at startup.
 */
public class VaultSecretsAdapter implements SecretsPort {

    private final WebClient webClient;
    private final String kvMount;
    private final String valueKey;

    /**
     * @param webClient a WebClient whose base URL points at Vault and that carries the {@code X-Vault-Token} header
     * @param kvMount   the KV v2 mount path (e.g. {@code "secret"})
     * @param valueKey  which field within the secret to return (e.g. {@code "value"})
     */
    public VaultSecretsAdapter(WebClient webClient, String kvMount, String valueKey) {
        this.webClient = webClient;
        this.kvMount = kvMount;
        this.valueKey = valueKey;
    }

    @Override
    public Mono<String> getSecret(String name) {
        return webClient.get()
                .uri("/v1/{mount}/data/{name}", kvMount, name)
                .retrieve()
                .bodyToMono(VaultKvResponse.class)
                .map(response -> {
                    Object value = (response.data() != null && response.data().data() != null)
                            ? response.data().data().get(valueKey) : null;
                    if (value == null) {
                        throw new IllegalStateException(
                                "Secret '" + name + "' (field '" + valueKey + "') not found in Vault");
                    }
                    return value.toString();
                })
                .onErrorMap(error -> error instanceof IllegalStateException ? error
                        : new IllegalStateException("Failed to read secret '" + name + "' from Vault", error));
    }

    /** KV v2 read response: {@code {"data": {"data": {<kv>}, "metadata": {...}}}}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record VaultKvResponse(VaultKvData data) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record VaultKvData(Map<String, Object> data) {
    }
}
