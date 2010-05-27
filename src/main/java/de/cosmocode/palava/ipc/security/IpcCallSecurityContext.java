/**
 * Copyright 2010 CosmoCode GmbH
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

package de.cosmocode.palava.ipc.security;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.inject.Inject;

import de.cosmocode.palava.core.Registry;
import de.cosmocode.palava.core.lifecycle.Disposable;
import de.cosmocode.palava.core.lifecycle.LifecycleException;
import de.cosmocode.palava.ipc.IpcCall;
import de.cosmocode.palava.ipc.IpcCallCreateEvent;
import de.cosmocode.palava.ipc.IpcCallDestroyEvent;

/**
 * A listener for the {@link IpcCallCreateEvent} and {@link IpcCallDestroyEvent}
 * which keeps track of the correct security context.
 * 
 * @author Tobias Sarnowski
 * @author Willi Schoenborn
 */
final class IpcCallSecurityContext implements IpcCallCreateEvent, IpcCallDestroyEvent, Disposable {
    
    private static final Logger LOG = LoggerFactory.getLogger(IpcCallSecurityContext.class);

    private static final String CALL_KEY = "SECURITY_SUBJECT_THREAD_STATE";
    private final Registry registry;

    @Inject
    public IpcCallSecurityContext(Registry registry) {
        this.registry = Preconditions.checkNotNull(registry, "Registry");
        registry.register(IpcCallCreateEvent.class, this);
        registry.register(IpcCallDestroyEvent.class, this);
    }

    @Override
    public void dispose() throws LifecycleException {
        registry.remove(this);
    }

    @Override
    public void eventIpcCallCreate(IpcCall call) {
        final Session session = new IpcSessionAdapter(call.getConnection().getSession());
        final Subject subject = new Subject.Builder().session(session).buildSubject();

        final SubjectThreadState state = new SubjectThreadState(subject);
        call.set(CALL_KEY, state);

        LOG.trace("Switching thread to subject {} with session {}", subject, session);
        state.bind();

        if (LOG.isDebugEnabled()) {
            if (subject.getPrincipal() == null) {
                LOG.debug("Calling command anonymously");
            } else {
                LOG.debug("Calling command as \"{}\"", subject.getPrincipal());
            }
        }
    }

    @Override
    public void eventIpcCallDestroy(IpcCall call) {
        final SubjectThreadState state = call.remove(CALL_KEY);

        LOG.trace("Switching thread back to pre-call state");
        state.restore();
    }
    
}
