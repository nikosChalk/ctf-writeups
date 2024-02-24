

Java.perform(function() {
    Java.use("com.inso.ins24.NoteAPIActivity").onCreate.implementation = function(a1) {
        console.log("onCreate invoked")
        return this.onCreate(a1)
    }
    console.log("Hooks initialized");
})

