package craterstudio.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.*;

import craterstudio.streams.AsyncOutputStream;

public class Logging {
   
   private static Handler asyncHandler(String path) throws IOException {
      return new StreamHandler(new AsyncOutputStream(new FileOutputStream(new File(path))), new XMLFormatter());
   }
   
   public static final Handler handler;
   
   static {
      
      String path = "./logs/_.xml";
      try {
         handler = asyncHandler(path);
      }
      catch (IOException exc) {
         throw new IllegalStateException(exc);
      }
   }
   
   public static synchronized java.util.logging.Logger init(Class< ? > clazz) {
      String name = clazz.getName();
      
      java.util.logging.Logger log = java.util.logging.Logger.getLogger(name);
      
      log.setLevel(Level.ALL); //
      try {
         boolean isInstalled = false;
         for (Handler handler : log.getHandlers()) {
            if (handler instanceof FileHandler) {
               isInstalled = true;
            }
         }
         
         if (!isInstalled) {
            String path = "./logs/" + name + ".xml";
            log.addHandler(asyncHandler(path));
            
            if (handler != null) {
               log.addHandler(handler);
            }
         }
      }
      catch (IOException exc) {
         exc.printStackTrace();
      }
      
      return log;
   }
}