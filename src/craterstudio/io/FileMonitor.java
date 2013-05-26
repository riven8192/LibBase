/*
 * Created on Aug 9, 2005
 */
package craterstudio.io;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class FileMonitor
{
   private final File file;

   public FileMonitor(File file)
   {
      this.file = file;

      this.startWithCreateEvent = false;
      this.updatingIdleTime = 3000;
   }

   /**
    * 
    */

   private boolean startWithCreateEvent;

   public final void setStartWithCreateEvent(boolean startWithCreateEvent)
   {
      this.startWithCreateEvent = startWithCreateEvent;
   }

   /**
    * 
    */

   private long updatingIdleTime;

   public final void setUpdatingTimeout(long updatingTimeout)
   {
      this.updatingIdleTime = updatingTimeout;
   }

   /**
    * LISTENERS
    */

   private final List<FileListener> listeners = new ArrayList<FileListener>();

   public final void addFileListener(FileListener listener)
   {
      synchronized (listeners)
      {
         listeners.add(listener);
      }
   }

   public final void removeFileListener(FileListener listener)
   {
      synchronized (listeners)
      {
         listeners.remove(listener);
      }
   }

   public final void removeAllFileListeners()
   {
      synchronized (listeners)
      {
         listeners.clear();
      }
   }

   /**
    * FIRE EVENTS
    */

   private final void fireFileCreatedEvent(File file)
   {
      synchronized (listeners)
      {
         for (FileListener l : listeners)
         {
            l.fileCreated(file);
         }
      }
   }

   private final void fireFileUpdatingEvent(File file)
   {
      synchronized (listeners)
      {
         for (FileListener l : listeners)
         {
            l.fileUpdating(file);
         }
      }
   }

   private final void fireFileUpdatedEvent(File file)
   {
      synchronized (listeners)
      {
         for (FileListener l : listeners)
         {
            l.fileUpdated(file);
         }
      }
   }

   private final void fireFileDeletedEvent(File file, boolean wasDirectory)
   {
      synchronized (listeners)
      {
         for (FileListener l : listeners)
         {
            l.fileDeleted(file, wasDirectory);
         }
      }
   }

   MyFile          previousFile;
   private boolean firstTime = true;

   public void check()
   {
      if (firstTime)
      {
         if (this.startWithCreateEvent)
            previousFile = null;
         else
            previousFile = wrap(this.file);

         firstTime = false;
      }

      // get contents of dir
      MyFile currentFile = wrap(this.file);

      // compare

      switch (this.isNew(currentFile, previousFile))
      {
         case -1:
            switch (this.isUpd(currentFile, previousFile))
            {
               case -1:
                  break;
               case 0:
                  this.fireFileUpdatingEvent(currentFile.backing);
                  this.ignoreUpdate(currentFile, previousFile);
                  break;
               case +1:
                  this.fireFileUpdatedEvent(currentFile.backing);
                  break;
            }
            break;

         case 0:
            currentFile = null;
            break;

         case +1:
            this.fireFileCreatedEvent(currentFile.backing);
            break;
      }

      // isDel
      if (previousFile != null && !currentFile.backing.exists())
      {
         this.fireFileDeletedEvent(currentFile.backing, currentFile.isDir);
      }

      previousFile = currentFile;
   }

   private final int isNew(MyFile current, MyFile prev)
   {
      if (prev == null)
      {
         long tAgo = System.currentTimeMillis() - current.cachedMod;
         return (tAgo < this.updatingIdleTime) ? 0 : +1;
      }

      return -1;
   }

   private final int isUpd(MyFile current, MyFile prev)
   {
      if (prev == null)
         throw new IllegalStateException("File not found: " + current.backing.getAbsolutePath());

      long tDiff = prev.cachedMod - current.cachedMod;
      if (tDiff == 0)
         return -1;
      long tAgo = System.currentTimeMillis() - current.cachedMod;
      return (tAgo < this.updatingIdleTime) ? 0 : +1;
   }

   private final void ignoreUpdate(MyFile current, MyFile prev)
   {
      if (prev == null)
         throw new IllegalStateException("File not found: " + current.backing.getAbsolutePath());

      current.cachedMod = prev.cachedMod;
   }

   private class MyFile
   {
      MyFile(File file)
      {
         this.isDir = file.isDirectory();
         this.backing = file;
         this.cachedMod = file.lastModified();
      }

      final boolean isDir;
      final File    backing;
      long          cachedMod;
   }

   private final MyFile wrap(File file)
   {
      return new MyFile(file);
   }
}
