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

import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import de.cosmocode.palava.ipc.IpcSession;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.lang.Object;import java.lang.Override;import java.lang.String;import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author Tobias Sarnowski
 */
public class IpcSessionAdapter implements Session {

    private static final Logger LOG = LoggerFactory.getLogger(IpcSessionAdapter.class);

    private static final Function<Map.Entry<Object, Object>, Object> GET_KEY = new Function<Map.Entry<Object, Object>, Object>() {

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
        return "{IpcSessionAdapter->" + session.toString() + "}";
    }
}
