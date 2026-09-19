export default (err,req,res,next)=>{
    console.error(err);
    res.status(err.status || 500).json({message:err.status<500 ? err.message :"Internal server error"})
}