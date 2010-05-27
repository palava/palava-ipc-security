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

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;

import de.cosmocode.palava.ipc.IpcSession;
import de.cosmocode.patterns.Adapter;

/**
 * An adapter from {@link IpcSession} to {@link Session}.
 * 
 * @author Tobias Sarnowski
 * @author Willi Schoenborn
 */
@Adapter(Session.class)
public class IpcSessionAdapter implements Session {

    private static final Logger LOG = LoggerFactory.getLogger(IpcSessionAdapter.class);

    private static final Function<Entry<Object, Object>, Object> GET_KEY = 
        new Function<Entry<Object, Object>, Object>() {
    
            @Override
            public Object apply(Map.Entry<Object, Object> from) {
                return from.getKey();
            }
    
        };

    private IpcSession session;

    public IpcSessionAdapter(IpcSession ipcSession) {
        this.session = ipcSession;
    }

    @Override
    public Serializable getId() {
        return session.getSessionId();
    }

    @Override
    public Date getStartTimestamp() {
        return session.startedAt();
    }

    @Override
    public Date getLastAccessTime() {
        return session.lastAccessTime();
    }

    @Override
    public long getTimeout() throws InvalidSessionException {
        return session.getTimeout(TimeUnit.MILLISECONDS);
    }

    @Override
    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        session.setTimeout(maxIdleTimeInMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public String getHost() {
        return session.getIdentifier();
    }

    @Override
    public void touch() throws InvalidSessionException {
        session.touch();
    }

    @Override
    public void stop() throws InvalidSessionException {
        LOG.debug("stopping/clearing session");
        session.clear();
    }

    @Override
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return ImmutableSet.copyOf(Iterables.transform(session, GET_KEY));
    }

    @Override
    public Object getAttribute(Object key) throws InvalidSessionException {
        return session.get(key);
    }

    @Override
    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        session.set(key, value);
    }

    @Override
    public Object removeAttribute(Object key) throws InvalidSessionException {
        return session.remove(key);
    }

    @Override
    public String toString() {
        return String.format("IpcSessionAdapter [session=%s]", session);
    }
    
}
