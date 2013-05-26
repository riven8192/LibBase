/*
 * Created on 21 mrt 2008
 */

package craterstudio.io;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import craterstudio.text.Text;

public class Resources {
   private static final Map<String, byte[]>        cache            = new HashMap<String, byte[]>();
   private static final Map<String, BufferedImage> images           = new HashMap<String, BufferedImage>();
   
   private static final ThreadLocal<ClassLoader>   localClassloader = new ThreadLocal<ClassLoader>();
   private static final ThreadLocal<Boolean>       localAllowCache  = new ThreadLocal<Boolean>();
   
   public static void overrideThreadLocalClassLoader(ClassLoader loader, boolean allowCache) {
      localClassloader.set(loader);
      localAllowCache.set(Boolean.valueOf(allowCache));
   }
   
   public static String loadString(String path) {
      byte[] raw = Resources.loadBytes(path);
      if (raw == null)
         throw new IllegalStateException("resource not found: " + path);
      return Text.utf8(raw);
   }
   
   public static InputStream fetchStream(String path) {
      // ensure class loaders
      ClassLoader[] loaders = new ClassLoader[3];
      loaders[0] = localClassloader.get(); // can be null
      loaders[1] = Thread.currentThread().getContextClassLoader();
      loaders[2] = Resources.class.getClassLoader();
      
      for (ClassLoader loader : loaders) {
         if (loader == null)
            continue;
         
         InputStream is = loader.getResourceAsStream(path);
         if (is == null)
            continue;
         return is;
      }
      
      return null;
   }
   
   public static byte[] loadBytes(String path) {
      Boolean allowCacheObj = localAllowCache.get();
      if (allowCacheObj == null)
         allowCacheObj = Boolean.TRUE;
      boolean allowCache = allowCacheObj.booleanValue();
      
      if (allowCache && cache.containsKey(path)) {
         return cache.get(path);
      }
      
      // ensure class loaders
      ClassLoader[] loaders = new ClassLoader[3];
      loaders[0] = localClassloader.get(); // can be null
      loaders[1] = Thread.currentThread().getContextClassLoader();
      loaders[2] = Resources.class.getClassLoader();
      
      byte[] raw = null;
      
      for (ClassLoader loader : loaders) {
         if (loader == null)
            continue;
         
         InputStream is = loader.getResourceAsStream(path);
         if (is == null)
            continue;
         
         raw = Streams.readStream(is);
         if (raw == null)
            continue;
         
         break;
      }
      
      if (raw == null) {
         System.out.println("warning: resource not found in classloaders: " + path);
      }
      
      if (allowCache) {
         cache.put(path, raw);
      }
      
      return raw;
   }
   
   public static BufferedImage loadImage(String path) {
      if (images.containsKey(path)) {
         return images.get(path);
      }
      
      byte[] raw = Resources.loadBytes(path);
      if (raw == null)
         return null;
      
      BufferedImage image = null;
      
      try {
         image = ImageIO.read(new ByteArrayInputStream(raw));
      }
      catch (IOException exc) {
         exc.printStackTrace();
         image = null;
      }
      
      images.put(path, image);
      return image;
   }
   
   public static void flush() {
      cache.clear();
      images.clear();
   }
}
