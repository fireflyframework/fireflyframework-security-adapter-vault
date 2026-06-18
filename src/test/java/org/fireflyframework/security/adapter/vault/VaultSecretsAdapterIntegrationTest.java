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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.Map;

/**
 * Real integration test of the Vault SecretsPort adapter against a live HashiCorp Vault (Docker)
 * running in dev mode. Writes a KV v2 secret, then verifies field reads and the fail-closed
 * behaviour for a missing secret.
 */
@Testcontainers
class VaultSecretsAdapterIntegrationTest {

    @Container
    static final GenericContainer<?> VAULT = new GenericContainer<>("hashicorp/vault:1.15")
            .withExposedPorts(8200)
            .withEnv("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .withCommand("server", "-dev")
            .waitingFor(Wait.forHttp("/v1/sys/health").forPort(8200).forStatusCode(200));

    static WebClient webClient;

    @BeforeAll
    static void writeSecret() {
        String baseUrl = "http://" + VAULT.getHost() + ":" + VAULT.getMappedPort(8200);
        webClient = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("X-Vault-Token", "root")
                .build();

        webClient.post().uri("/v1/secret/data/db")
                .bodyValue(Map.of("data", Map.of("value", "s3cr3t", "username", "admin")))
                .retrieve().toBodilessEntity().block();
    }

    private VaultSecretsAdapter adapter(String field) {
        return new VaultSecretsAdapter(webClient, "secret", field);
    }

    @Test
    void readsSecretValueField() {
        StepVerifier.create(adapter("value").getSecret("db")).expectNext("s3cr3t").verifyComplete();
    }

    @Test
    void readsNamedField() {
        StepVerifier.create(adapter("username").getSecret("db")).expectNext("admin").verifyComplete();
    }

    @Test
    void missingSecretFailsClosed() {
        StepVerifier.create(adapter("value").getSecret("does-not-exist"))
                .expectError(IllegalStateException.class).verify();
    }
}
