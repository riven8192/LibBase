package craterstudio.misc;

import static java.lang.Math.*;

import java.awt.Color;

import craterstudio.math.EasyMath;

public class ColorHSL
{
   public static final float RED_HUE    = ColorHSL.fromColor(Color.RED)[0];
   public static final float ORANGE_HUE = ColorHSL.fromColor(Color.ORANGE)[0];
   public static final float YELLOW_HUE = ColorHSL.fromColor(Color.YELLOW)[0];
   public static final float GREEN_HUE  = ColorHSL.fromColor(Color.GREEN)[0];
   public static final float CYAN_HUE   = ColorHSL.fromColor(Color.CYAN)[0];
   public static final float BLUE_HUE   = ColorHSL.fromColor(Color.BLUE)[0];
   public static final float PURPLE_HUE = ColorHSL.fromColor(new Color(255, 0, 255))[0];

   public static final float[] fromColor(Color color)
   {
      return ColorHSL.fromColor(color.getRed(), color.getGreen(), color.getBlue());
   }

   public static final float[] fromColor(int r, int g, int b)
   {
      int[] rgb = new int[] { r, g, b };
      float[] hsl = new float[3];
      ColorHSL.rgb2hsl(rgb, hsl);
      return hsl;
   }

   public static final Color toColor(float[] hsl)
   {
      int[] rgb = new int[3];
      ColorHSL.hsl2rgb(hsl, rgb);
      return new Color(rgb[0], rgb[1], rgb[2]);
   }

   public static final Color toColor(float h, float s, float l)
   {
      return ColorHSL.toColor(new float[] { h, s, l });
   }

   //
   public static final Color lerp(float t, Color a, Color b)
   {
      int[] aRGB = new int[3];
      int[] bRGB = new int[3];

      aRGB[0] = a.getRed();
      aRGB[1] = a.getGreen();
      aRGB[2] = a.getBlue();

      bRGB[0] = b.getRed();
      bRGB[1] = b.getGreen();
      bRGB[2] = b.getBlue();

      //

      float[] aHSL = new float[3];
      float[] bHSL = new float[3];
      ColorHSL.rgb2hsl(aRGB, aHSL);
      ColorHSL.rgb2hsl(bRGB, bHSL);

      //

      float[] cHSL = new float[3];
      cHSL[0] = EasyMath.lerp(aHSL[0], bHSL[0], t);
      cHSL[1] = EasyMath.lerp(aHSL[1], bHSL[1], t);
      cHSL[2] = EasyMath.lerp(aHSL[2], bHSL[2], t);

      //

      int[] cRGB = new int[3];
      ColorHSL.hsl2rgb(cHSL, cRGB);

      return new Color(cRGB[0], cRGB[1], cRGB[2]);
   }

   public static final Color lerpWithCap(float t, Color a, Color b)
   {
      if (t <= 0.0f)
         return a;
      if (t >= 1.0f)
         return b;
      return lerp(t, a, b);
   }

   public static final Color setBrightness(Color c, float delta)
   {
      int[] RGB = new int[3];
      float[] HSL = new float[3];

      RGB[0] = c.getRed();
      RGB[1] = c.getGreen();
      RGB[2] = c.getBlue();

      ColorHSL.rgb2hsl(RGB, HSL);
      HSL[2] = delta;
      ColorHSL.hsl2rgb(HSL, RGB);

      return new Color(RGB[0], RGB[1], RGB[2]);
   }

   public static final Color adjust(Color c, float hue, float sat, float lig)
   {
      int[] RGB = new int[3];
      float[] HSL = new float[3];

      RGB[0] = c.getRed();
      RGB[1] = c.getGreen();
      RGB[2] = c.getBlue();

      ColorHSL.rgb2hsl(RGB, HSL);
      HSL[0] += hue;
      HSL[1] += sat;
      HSL[2] += lig;
      ColorHSL.hsl2rgb(HSL, RGB);

      return new Color(RGB[0], RGB[1], RGB[2]);
   }

   public static final Color adjustHue(Color c, float delta)
   {
      int[] RGB = new int[3];
      float[] HSL = new float[3];

      RGB[0] = c.getRed();
      RGB[1] = c.getGreen();
      RGB[2] = c.getBlue();

      ColorHSL.rgb2hsl(RGB, HSL);
      HSL[0] += delta;
      ColorHSL.hsl2rgb(HSL, RGB);

      return new Color(RGB[0], RGB[1], RGB[2]);
   }

   public static final Color adjustBrightness(Color c, float delta)
   {
      int[] RGB = new int[3];
      float[] HSL = new float[3];

      RGB[0] = c.getRed();
      RGB[1] = c.getGreen();
      RGB[2] = c.getBlue();

      ColorHSL.rgb2hsl(RGB, HSL);
      HSL[2] += delta;
      ColorHSL.hsl2rgb(HSL, RGB);

      return new Color(RGB[0], RGB[1], RGB[2]);
   }

   public static final int[] rgb2arr(int rgb)
   {
      return rgb2arr(rgb, new int[3]);
   }

   public static final int[] rgb2arr(int rgb, int[] arr)
   {
      arr[0] = (rgb >> 16) & 0xFF;
      arr[1] = (rgb >> 8) & 0xFF;
      arr[2] = (rgb >> 0) & 0xFF;
      return arr;
   }

   public static final int arr2rgb(int[] arr)
   {
      int rgb = 0;
      rgb |= (arr[0] & 0xFF) << 16;
      rgb |= (arr[1] & 0xFF) << 8;
      rgb |= (arr[2] & 0xFF) << 0;
      return rgb;
   }

   public static final void rgb2hsl(int[] rgb, float[] hsl)
   {
      float R = rgb[0] / 255.0f;
      float G = rgb[1] / 255.0f;
      float B = rgb[2] / 255.0f;

      float MAX = max(R, max(G, B));
      float MIN = min(R, min(G, B));
      float H, L, S;

      if (MIN == MAX)
         H = 0.0f;
      else if (R == MAX)
         H = 0.16666666f * ((G - B) / (MAX - MIN)) + 0.00000000f;
      else if (G == MAX)
         H = 0.16666666f * ((B - R) / (MAX - MIN)) + 0.33333333f;
      else
         H = 0.16666666f * ((R - G) / (MAX - MIN)) + 0.66666666f;

      L = 0.5f * (MIN + MAX);
      if (L == 0.0f || (MIN == MAX))
         S = 0.0f;
      else if (L <= 0.5f)
         S = (MAX - MIN) / (2 * L);
      else
         S = (MAX - MIN) / (2 - 2 * L);

      hsl[0] = absMod(H, 1.0f);
      hsl[1] = S;
      hsl[2] = L;
   }

   public static final int[] hsl2rgb(float[] hsl, int[] rgb)
   {
      float H = hsl[0];
      float S = hsl[1];
      float L = hsl[2];

      float R, G, B;

      if (S == 0.0f)
      {
         R = G = B = L;
      }
      else
      {
         float Q = (L < 0.5f) ? (L * (1.0f + S)) : ((L + S) - (L * S));
         float P = 2.0f * L - Q;
         float Hk = absMod(H, 1.0f);

         R = convert(Q, P, Hk + 0.33333333333f);
         G = convert(Q, P, Hk + 0.00000000000f);
         B = convert(Q, P, Hk - 0.33333333333f);
      }

      rgb[0] = (int) (clamp(R, 0.0f, 1.0f) * 255.0f);
      rgb[1] = (int) (clamp(G, 0.0f, 1.0f) * 255.0f);
      rgb[2] = (int) (clamp(B, 0.0f, 1.0f) * 255.0f);

      return rgb;
   }

   private static final float convert(float Q, float P, float Tx)
   {
      Tx = absMod(Tx, 1.0f);
      if (Tx < 1.0f / 6.0f)
         return P + ((Q - P) * 6.0f * Tx);
      if (Tx < 3.0f / 6.0f)
         return Q;
      if (Tx < 4.0f / 6.0f)
         return P + ((Q - P) * 6.0f * (4.0f / 6.0f - Tx));
      return P;
   }

   public static final float absMod(float val, float max)
   {
      return ((val % max) + max) % max;
   }

   public static final float clamp(float cur, float min, float max)
   {
      return (cur < min ? min : (cur > max ? max : cur));
   }
}
