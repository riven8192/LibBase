package craterstudio.misc;

import craterstudio.text.Text;

public class CSV
{
   private String[][] cells = new String[4][4];

   /**
    * GET
    */

   public final String get(String cell)
   {
      int[] result = new int[2];
      getCoords(cell, result);
      int row = result[0];
      int col = result[1];

      return this.get(row, col);
   }

   public final String get(int row, int col)
   {
      if (row >= cells.length)
         return "";
      if (col >= cells[row].length)
         return "";

      if (cells[row][col] == null)
         return "";
      return cells[row][col];
   }

   /**
    * SET
    */

   public final void set(String cell, String value)
   {
      int[] result = new int[2];
      getCoords(cell, result);
      int row = result[0];
      int col = result[1];

      this.set(col, row, value);
   }

   public final void set(int col, int row, String value)
   {
      if (row >= cells.length)
      {
         String[][] cells0 = new String[cells.length * 2 + 1][];
         for (int i = 0; i < cells.length; i++)
            cells0[i] = cells[i];
         for (int i = cells.length; i < cells0.length; i++)
            cells0[i] = new String[0];
         cells = cells0;
      }

      if (col >= cells[row].length)
      {
         String[] cells0 = new String[cells[row].length * 2 + 1];
         System.arraycopy(cells[row], 0, cells0, 0, cells[row].length);
         cells[row] = cells0;
      }

      cells[row][col] = value;
   }

   /**
    * STRING
    */

   public final void fromString(String in, char fieldSeparator)
   {
      String[] lines = Text.splitOnLines(in);

      for (int row = 0; row < lines.length; row++)
      {
         String[] cells = Text.split(lines[row], fieldSeparator);

         for (int col = 0; col < cells.length; col++)
         {
            this.set(col, row, cells[col]);
         }
      }
   }

   public final String toString(char fieldSeparator)
   {
      StringBuilder sb = new StringBuilder();

      int lastRow = -1;
      for (int row = cells.length - 1; row >= 0; row--)
      {
         if (cells[row].length > 0)
         {
            int lastCol = -1;
            for (int col = cells[row].length - 1; col >= 0; col--)
            {
               if (cells[row][col] == null)
                  continue;
               if (cells[row][col].equals(""))
                  continue;

               lastCol = col;
               break;
            }

            if (lastCol == -1)
               continue;

            lastRow = row;
            break;
         }
      }

      for (int row = 0; row <= lastRow; row++)
      {
         int lastCol = -1;
         for (int col = cells[row].length - 1; col >= 0; col--)
         {
            if (cells[row][col] == null)
               continue;
            if (cells[row][col].equals(""))
               continue;

            lastCol = col;
            break;
         }

         for (int col = 0; col <= lastCol; col++)
         {
            if (cells[row][col] != null)
               sb.append(cells[row][col]);

            if (col != lastCol)
               sb.append(fieldSeparator);
         }

         sb.append("\r\n");
      }

      return sb.toString();
   }

   /**
    * COORDS
    */

   public static final void getCoords(String coords, int[] result)
   {
      coords = coords.toUpperCase();

      int col = 0;
      int row = 0;

      for (int i = 0; i < coords.length(); i++)
      {
         char c = coords.charAt(i);

         if (c >= 'A' && c <= 'Z')
         {
            col *= 26;
            col += (c - 'A') + 1; // A == 1
         }
         else
         {
            row *= 10;
            row += c - '0';
         }
      }

      // cell N is array-index N-1
      row -= 1;
      col -= 1;

      result[0] = row;
      result[1] = col;
   }
}