/*
 * Copyright (C)2009 - SSHJ Contributors
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
package com.hierynomus.sshj.transport.kex;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.kex.MLKEM768X25519SHA256;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Connects to the SSH server identified by {@code host}/{@code port}/{@code user}/{@code password},
 * forcing the {@code mlkem768x25519-sha256} key exchange, and prints the negotiated KEX
 * algorithm both as observed via the {@link net.schmizz.sshj.transport.AlgorithmsVerifier}
 * hook and via the live {@link net.schmizz.sshj.transport.NegotiatedAlgorithms} on the transport.
 *
 * <p>Defaults are tailored to a local Erlang SSH server: {@code 0.0.0.0:2024} with
 * {@code admin/admin}. Override via JVM system properties
 * {@code -Dsshj.host=...}, {@code -Dsshj.port=...}, {@code -Dsshj.user=...},
 * {@code -Dsshj.password=...}.</p>
 */
public class MLKEMHybridKexConnectMain {

    public static void main(final String[] args) throws Exception {
        final String host = System.getProperty("sshj.host", "0.0.0.0");
        final int port = Integer.parseInt(System.getProperty("sshj.port", "2024"));
        final String user = System.getProperty("sshj.user", "admin");
        final String password = System.getProperty("sshj.password", "admin");

        // Restrict the client proposal to a single KEX so the server MUST agree
        // to mlkem768x25519-sha256 or the negotiation will fail. This is the strongest
        // possible proof: a successful handshake means it was actually used.
        final Config config = new DefaultConfig();
        config.setKeyExchangeFactories(List.of(new MLKEM768X25519SHA256.Factory()));

        final AtomicReference<String> negotiatedKex = new AtomicReference<>();

        try (SSHClient client = new SSHClient(config)) {
            // No host key verification — this is a local connectivity check, not auth security.
            client.addHostKeyVerifier(new PromiscuousVerifier());
            client.addAlgorithmsVerifier(negotiated -> {
                negotiatedKex.set(negotiated.getKeyExchangeAlgorithm());
                System.out.println("[verifier] Negotiated KEX algorithm: " + negotiated.getKeyExchangeAlgorithm());
                System.out.println("[verifier] Server host key algorithm: " + negotiated.getSignatureAlgorithm());
                System.out.println("[verifier] C2S cipher: " + negotiated.getClient2ServerCipherAlgorithm());
                System.out.println("[verifier] S2C cipher: " + negotiated.getServer2ClientCipherAlgorithm());
                return true;
            });

            System.out.println("Connecting to " + host + ":" + port + " as " + user
                    + " forcing KEX = mlkem768x25519-sha256 ...");
            client.connect(host, port);
            System.out.println("TCP + SSH transport established. Server ID: " + client.getTransport().getServerVersion());

            client.authPassword(user, password);
            System.out.println("Authentication successful.");

            final String observed = negotiatedKex.get();
            if (!"mlkem768x25519-sha256".equals(observed)) {
                throw new IllegalStateException(
                        "Expected negotiated KEX 'mlkem768x25519-sha256' but observed '" + observed + "'");
            }

            System.out.println();
            System.out.println("===========================================================");
            System.out.println(" SUCCESS: SSH session established with negotiated KEX = "
                    + observed);
            System.out.println("===========================================================");
        }
    }
}
