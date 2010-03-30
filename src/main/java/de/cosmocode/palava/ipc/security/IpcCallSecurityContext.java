/**
 * palava - a java-php-bridge
 * Copyright (C) 2007-2010  CosmoCode GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

package de.cosmocode.palava.ipc.security;

import com.google.inject.Inject;
import de.cosmocode.palava.core.Registry;
import de.cosmocode.palava.ipc.IpcCall;
import de.cosmocode.palava.ipc.IpcCallCreateEvent;
import de.cosmocode.palava.ipc.IpcCallDestroyEvent;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Tobias Sarnowski
 */
class IpcCallSecurityContext implements IpcCallCreateEvent, IpcCallDestroyEvent {
    private static final Logger LOG = LoggerFactory.getLogger(IpcCallSecurityContext.class);

    private static final String CALL_KEY = "SECURITY_SUBJECT_THREAD_STATE";

    @Inject
    IpcCallSecurityContext(Registry registry) {
        registry.register(IpcCallCreateEvent.class, this);
        registry.register(IpcCallDestroyEvent.class, this);
    }

    @Override
    public void eventIpcCallCreate(IpcCall call) {
        Session session = new IpcSessionAdapter(call.getConnection().getSession());
        Subject subject = (new Subject.Builder()).session(session).buildSubject();

        SubjectThreadState subjectThreadState = new SubjectThreadState(subject);
        call.set(CALL_KEY, subjectThreadState);

        LOG.debug("switching thread to subject {} with session {}", subject, session);
        subjectThreadState.bind();
    }

    @Override
    public void eventIpcCallDestroy(IpcCall call) {
        SubjectThreadState subjectThreadState = call.get(CALL_KEY);

        LOG.debug("switching thread back to pre-call state");
        subjectThreadState.clear();

        call.remove(CALL_KEY);
    }
}
